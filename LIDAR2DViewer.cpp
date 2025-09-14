#include "include/PcapLib/Lidar2DViewer.h"

Lidar2DViewer::Lidar2DViewer(int width, int height)
    : windowWidth(width), windowHeight(height),
      windowName("LIDAR 2D Viewer"), isWindowCreated(true),
      canvas(cv::Mat::zeros(height, width, CV_8UC3))  // Khởi tạo luôn
{
    cv::namedWindow(windowName, cv::WINDOW_AUTOSIZE);
}

Lidar2DViewer::~Lidar2DViewer() {
    close();
}

void Lidar2DViewer::update(const std::vector<cv::Point2f>& lidarPoints,
                           const cv::Scalar& pointColor,
                           int pointSize)
{
    if (lidarPoints.empty()) return;

    int radius = std::max(1, pointSize / 2);
    for (const auto& point : lidarPoints) {
        cv::circle(canvas, point, radius, pointColor, cv::FILLED);
    }
}



void Lidar2DViewer::show() {
    if (isWindowCreated) {
        cv::imshow(windowName, canvas);
    }
}

void Lidar2DViewer::close() {
    if (isWindowCreated) {
        cv::destroyWindow(windowName);
        isWindowCreated = false;
    }
}
